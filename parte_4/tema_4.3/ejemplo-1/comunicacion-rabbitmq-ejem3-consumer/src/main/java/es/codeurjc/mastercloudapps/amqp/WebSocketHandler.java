package es.codeurjc.mastercloudapps.amqp;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.AbstractWebSocketHandler;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@Component
public class WebSocketHandler extends AbstractWebSocketHandler {

	Logger logger = LoggerFactory.getLogger(WebSocketHandler.class);
	private WebSocketSession websocketSession;

	@Override
	public void handleTextMessage(WebSocketSession session, TextMessage message)
			throws InterruptedException, IOException {

		logger.info("Message received:" + message.getPayload());
		
		session.sendMessage(new TextMessage("Echo: "+ message.getPayload()));
	}

	@Override
	public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
		logger.info("User disconnected "+session.getId());
		websocketSession = null;
	}

	@Override
	public void afterConnectionEstablished(WebSocketSession session) throws Exception {
		logger.info("User connected "+session.getId());
				
		websocketSession = session;
	}
	
	public void sendMessage(ExampleData data) {
		if(websocketSession == null) {
			logger.info("No websocket connection. Message will not be forwarded");
			return;
		}
		String json;
		try {
			json = new ObjectMapper().writeValueAsString(data);
			websocketSession.sendMessage(new TextMessage(json));
		} catch (JacksonException e) {
			logger.error("Cannot convert to json: " + data.getData());
			throw new RuntimeException();
		} catch (IOException e) {
			logger.error("Exception sending message to WebSocketSession " + websocketSession.getId(), e);
			e.printStackTrace();
		}
	}
}