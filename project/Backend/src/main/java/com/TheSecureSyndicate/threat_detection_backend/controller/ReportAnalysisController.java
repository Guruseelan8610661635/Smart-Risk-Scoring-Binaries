package com.TheSecureSyndicate.threat_detection_backend.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class ReportAnalysisController {

    private static final Logger logger = LoggerFactory.getLogger(ReportAnalysisController.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Threat Detection Backend");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/analyze-report")
    public ResponseEntity<Map<String, Object>> analyzeReport(@RequestParam MultipartFile file) {
        try {
            // Check if file is JSON
            if (file.getSize() == 0) {
                return ResponseEntity.badRequest().body(createErrorResponse("File is empty"));
            }

            String fileName = file.getOriginalFilename();
            if (fileName == null || (!fileName.endsWith(".json") && !file.getContentType().contains("json"))) {
                return ResponseEntity.badRequest().body(createErrorResponse("Only JSON files are supported"));
            }

            // Parse JSON
            String content = new String(file.getBytes(), StandardCharsets.UTF_8);
            JsonNode reportNode = objectMapper.readTree(content);

            // Create analysis response
            Map<String, Object> response = new HashMap<>();
            response.put("filename", fileName);
            response.put("timestamp", Instant.now().toString());
            response.put("fileSize", file.getSize());
            response.put("binaryId", UUID.randomUUID().toString());

            // Extract basic metrics from report
            extractMetrics(reportNode, response);

            // Analyze report for alerts and issues
            List<Map<String, String>> alerts = analyzeForIssues(reportNode);
            response.put("alerts", alerts);

            // Add full analysis data
            response.put("analysis", reportNode);

            // Calculate risk level based on alerts
            String riskLevel = calculateRiskLevel(alerts);
            response.put("riskLevel", riskLevel);

            // Calculate trust score
            double trustScore = calculateTrustScore(reportNode, alerts);
            response.put("trustScore", trustScore);

            logger.info("Successfully analyzed report: {}", fileName);
            return ResponseEntity.ok(response);

        } catch (IOException e) {
            logger.error("Error reading file: {}", e.getMessage());
            return ResponseEntity.badRequest().body(createErrorResponse("Error reading file: " + e.getMessage()));
        } catch (Exception e) {
            logger.error("Error analyzing report: {}", e.getMessage());
            return ResponseEntity.badRequest().body(createErrorResponse("Error analyzing report: " + e.getMessage()));
        }
    }

    private void extractMetrics(JsonNode reportNode, Map<String, Object> response) {
        try {
            // Try to extract common metrics from the report
            if (reportNode.has("sha256")) {
                response.put("sha256", reportNode.get("sha256").asText());
            }
            if (reportNode.has("entropy")) {
                response.put("entropy", reportNode.get("entropy").asDouble());
            } else {
                response.put("entropy", 0.0);
            }
            if (reportNode.has("size")) {
                response.put("fileSize", reportNode.get("size").asLong());
            }
        } catch (Exception e) {
            logger.warn("Error extracting metrics: {}", e.getMessage());
        }
    }

    private List<Map<String, String>> analyzeForIssues(JsonNode reportNode) {
        List<Map<String, String>> alerts = new ArrayList<>();

        try {
            // Check for suspicious patterns
            if (reportNode.has("behaviors")) {
                JsonNode behaviors = reportNode.get("behaviors");
                if (behaviors.isArray()) {
                    for (JsonNode behavior : behaviors) {
                        String behaviorStr = behavior.asText().toLowerCase();
                        if (behaviorStr.contains("inject") || behaviorStr.contains("hook")) {
                            alerts.add(createAlert("High", "Code injection detected"));
                        }
                        if (behaviorStr.contains("registry") && behaviorStr.contains("modify")) {
                            alerts.add(createAlert("High", "Registry modification detected"));
                        }
                        if (behaviorStr.contains("delete") || behaviorStr.contains("overwrite")) {
                            alerts.add(createAlert("Medium", "File system manipulation detected"));
                        }
                    }
                }
            }

            // Check for suspicious APIs
            if (reportNode.has("apicalls")) {
                JsonNode apiCalls = reportNode.get("apicalls");
                if (apiCalls.isArray()) {
                    for (JsonNode call : apiCalls) {
                        String apiName = call.asText().toLowerCase();
                        if (apiName.contains("createremotethread") || apiName.contains("virtualalloc")) {
                            alerts.add(createAlert("High", "Process injection API detected: " + apiName));
                        }
                        if (apiName.contains("regsetvalueex") || apiName.contains("regcreatekeyex")) {
                            alerts.add(createAlert("Medium", "Registry operation detected"));
                        }
                    }
                }
            }

            // Check for network activity
            if (reportNode.has("network")) {
                JsonNode network = reportNode.get("network");
                if (network.isArray() && network.size() > 0) {
                    alerts.add(createAlert("Medium", "Network activity detected: " + network.size() + " connections"));
                }
            }

            // Check for dropped files
            if (reportNode.has("dropped")) {
                JsonNode dropped = reportNode.get("dropped");
                if (dropped.isArray() && dropped.size() > 0) {
                    alerts.add(createAlert("High", "Dropped files detected: " + dropped.size() + " file(s)"));
                }
            }

            // Check for mutex creation
            if (reportNode.has("mutexes")) {
                JsonNode mutexes = reportNode.get("mutexes");
                if (mutexes.isArray() && mutexes.size() > 0) {
                    alerts.add(createAlert("Low", "Mutex created (potential ransomware indicator)"));
                }
            }

        } catch (Exception e) {
            logger.warn("Error analyzing report for issues: {}", e.getMessage());
        }

        return alerts;
    }

    private Map<String, String> createAlert(String severity, String message) {
        Map<String, String> alert = new HashMap<>();
        alert.put("severity", severity);
        alert.put("message", message);
        return alert;
    }

    private String calculateRiskLevel(List<Map<String, String>> alerts) {
        if (alerts.isEmpty()) {
            return "Low";
        }

        int criticalCount = 0;
        int highCount = 0;

        for (Map<String, String> alert : alerts) {
            String severity = alert.get("severity");
            if ("Critical".equalsIgnoreCase(severity)) {
                criticalCount++;
            } else if ("High".equalsIgnoreCase(severity)) {
                highCount++;
            }
        }

        if (criticalCount > 0) {
            return "Critical";
        } else if (highCount >= 2) {
            return "High";
        } else if (highCount > 0 || alerts.size() >= 3) {
            return "Medium";
        } else {
            return "Low";
        }
    }

    private double calculateTrustScore(JsonNode reportNode, List<Map<String, String>> alerts) {
        double score = 100.0; // Start with 100

        // Deduct points for each alert
        for (Map<String, String> alert : alerts) {
            String severity = alert.get("severity");
            switch (severity) {
                case "Critical":
                    score -= 25;
                    break;
                case "High":
                    score -= 15;
                    break;
                case "Medium":
                    score -= 10;
                    break;
                case "Low":
                    score -= 5;
                    break;
            }
        }

        // Ensure score stays within bounds
        return Math.max(0, Math.min(100, score));
    }

    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("error", true);
        error.put("message", message);
        return error;
    }
}
