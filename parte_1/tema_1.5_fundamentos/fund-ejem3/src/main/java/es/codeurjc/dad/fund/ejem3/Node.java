package es.codeurjc.dad.fund.ejem3;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import es.codeurjc.dad.fund.ejem3.Messages.AppendEntries;
import es.codeurjc.dad.fund.ejem3.Messages.AppendResult;
import es.codeurjc.dad.fund.ejem3.Messages.Entry;
import es.codeurjc.dad.fund.ejem3.Messages.Message;
import es.codeurjc.dad.fund.ejem3.Messages.RequestVote;
import es.codeurjc.dad.fund.ejem3.Messages.Vote;

/**
 * Un nodo Raft simplificado (sin persistencia, sin cambios de configuración ni
 * snapshots). Suficiente para ver la elección de líder y la replicación del log.
 *
 * Índices del log empezando en 1, como en el artículo de Raft.
 */
public class Node {

	public enum State {
		FOLLOWER, CANDIDATE, LEADER
	}

	static final int HEARTBEAT_MS = 50;
	static final int ELECTION_MIN_MS = 150;
	static final int ELECTION_MAX_MS = 300;

	private final int id;
	private final int clusterSize;
	private final Cluster cluster;
	private final Random random;

	// Estado de Raft
	private State state = State.FOLLOWER;
	private long currentTerm;
	private Integer votedFor;
	private final List<Entry> log = new ArrayList<>();
	private int commitIndex;

	// Candidato
	private int votes;
	// Líder
	private final int[] nextIndex;
	private final int[] matchIndex;

	// Temporizadores
	private long electionDeadline;
	private long nextHeartbeat;

	Node(int id, int clusterSize, Cluster cluster, Random random) {
		this.id = id;
		this.clusterSize = clusterSize;
		this.cluster = cluster;
		this.random = random;
		this.nextIndex = new int[clusterSize];
		this.matchIndex = new int[clusterSize];
		resetElectionTimer(0);
	}

	// ------------------------------------------------------------ tiempo

	void tick(long now) {
		if (state == State.LEADER) {
			if (now >= nextHeartbeat) {
				replicate(now);
			}
		} else if (now >= electionDeadline) {
			startElection(now);
		}
	}

	private void resetElectionTimer(long now) {
		// Aleatorio para que no se presenten todos a la vez (votos divididos)
		electionDeadline = now + ELECTION_MIN_MS + random.nextInt(ELECTION_MAX_MS - ELECTION_MIN_MS);
	}

	// ------------------------------------------------------------ elección

	private void startElection(long now) {
		state = State.CANDIDATE;
		currentTerm++;
		votedFor = id;
		votes = 1;
		resetElectionTimer(now);
		for (int peer = 0; peer < clusterSize; peer++) {
			if (peer != id) {
				cluster.send(id, peer, new RequestVote(currentTerm, id, lastLogIndex(), lastLogTerm()));
			}
		}
	}

	private void onRequestVote(int from, RequestVote rv, long now) {
		boolean logOk = rv.lastLogTerm() > lastLogTerm()
				|| (rv.lastLogTerm() == lastLogTerm() && rv.lastLogIndex() >= lastLogIndex());
		boolean grant = rv.term() == currentTerm && (votedFor == null || votedFor == rv.candidate()) && logOk;
		if (grant) {
			votedFor = rv.candidate();
			resetElectionTimer(now);
		}
		cluster.send(id, from, new Vote(currentTerm, grant));
	}

	private void onVote(Vote v, long now) {
		if (state != State.CANDIDATE || v.term() != currentTerm || !v.granted()) {
			return;
		}
		votes++;
		if (votes > clusterSize / 2) {
			becomeLeader(now);
		}
	}

	private void becomeLeader(long now) {
		state = State.LEADER;
		Arrays.fill(nextIndex, log.size() + 1);
		Arrays.fill(matchIndex, 0);
		matchIndex[id] = log.size();
		cluster.leaderElected(id, currentTerm);
		replicate(now);
	}

	private void stepDown(long term, long now) {
		currentTerm = term;
		state = State.FOLLOWER;
		votedFor = null;
		resetElectionTimer(now);
	}

	// ------------------------------------------------------------ replicación

	/** Solo en el líder: añade una orden a su log. */
	int submit(String command) {
		if (state != State.LEADER) {
			throw new IllegalStateException("El nodo " + id + " no es el líder");
		}
		log.add(new Entry(currentTerm, command));
		matchIndex[id] = log.size();
		return log.size();
	}

	private void replicate(long now) {
		nextHeartbeat = now + HEARTBEAT_MS;
		for (int peer = 0; peer < clusterSize; peer++) {
			if (peer == id) {
				continue;
			}
			int prev = nextIndex[peer] - 1;
			List<Entry> entries = List.copyOf(log.subList(prev, log.size()));
			cluster.send(id, peer, new AppendEntries(currentTerm, id, prev, termAt(prev), entries, commitIndex));
		}
	}

	private void onAppendEntries(int from, AppendEntries ae, long now) {
		if (ae.term() < currentTerm) {
			cluster.send(id, from, new AppendResult(currentTerm, false, 0));
			return;
		}
		state = State.FOLLOWER; // hay un líder legítimo en este mandato
		resetElectionTimer(now);

		// ¿Coincide mi log con el del líder hasta prevLogIndex?
		if (ae.prevLogIndex() > log.size() || termAt(ae.prevLogIndex()) != ae.prevLogTerm()) {
			cluster.send(id, from, new AppendResult(currentTerm, false, 0));
			return;
		}
		int index = ae.prevLogIndex();
		for (Entry e : ae.entries()) {
			index++;
			if (index <= log.size() && log.get(index - 1).term() != e.term()) {
				// Conflicto: lo que hay a partir de aquí no está comprometido y se descarta
				log.subList(index - 1, log.size()).clear();
			}
			if (index > log.size()) {
				log.add(e);
			}
		}
		if (ae.leaderCommit() > commitIndex) {
			commitIndex = Math.min(ae.leaderCommit(), index);
		}
		cluster.send(id, from, new AppendResult(currentTerm, true, index));
	}

	private void onAppendResult(int from, AppendResult r) {
		if (state != State.LEADER || r.term() != currentTerm) {
			return;
		}
		if (!r.success()) {
			nextIndex[from] = Math.max(1, nextIndex[from] - 1); // retroceder y reintentar
			return;
		}
		matchIndex[from] = Math.max(matchIndex[from], r.matchIndex());
		nextIndex[from] = matchIndex[from] + 1;
		// Una entrada está COMPROMETIDA cuando está en la mayoría de los nodos
		// (y es del mandato actual del líder)
		for (int n = log.size(); n > commitIndex; n--) {
			final int candidate = n;
			long replicas = Arrays.stream(matchIndex).filter(m -> m >= candidate).count();
			if (log.get(n - 1).term() == currentTerm && replicas > clusterSize / 2) {
				commitIndex = n;
				break;
			}
		}
	}

	// ------------------------------------------------------------ mensajes

	void receive(int from, Message m, long now) {
		if (m.term() > currentTerm) {
			stepDown(m.term(), now); // alguien tiene un mandato más reciente
		}
		switch (m) {
			case RequestVote rv -> onRequestVote(from, rv, now);
			case Vote v -> onVote(v, now);
			case AppendEntries ae -> onAppendEntries(from, ae, now);
			case AppendResult r -> onAppendResult(from, r);
		}
	}

	// ------------------------------------------------------------ consultas

	private int lastLogIndex() {
		return log.size();
	}

	private long lastLogTerm() {
		return termAt(log.size());
	}

	private long termAt(int index) {
		return index == 0 ? 0 : log.get(index - 1).term();
	}

	public int id() {
		return id;
	}

	public State state() {
		return state;
	}

	public long term() {
		return currentTerm;
	}

	public int commitIndex() {
		return commitIndex;
	}

	public List<Entry> log() {
		return List.copyOf(log);
	}

	/** Las órdenes comprometidas: las que se pueden aplicar a la máquina de estados. */
	public List<String> committed() {
		return log.subList(0, commitIndex).stream().map(Entry::command).toList();
	}
}
