package es.codeurjc.mastercloudapps.ws;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ReportService {

    @Autowired
    private ReportRepository reportRepository;

    @Autowired
    private ReportGenerator reportGenerator;

    public Report createReport(String reportCreationData) {

        Report report = new Report();

        reportRepository.save(report);

        reportGenerator.createReport(report.getId(), reportCreationData);

        return report;
    }
}