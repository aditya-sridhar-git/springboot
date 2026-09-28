package com.cloudsec.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.ConcurrentWebSocketSessionDecorator;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * Fan-out of alerts, events and statistics to every connected dashboard.
 *
 * <p>Plain text frames carrying {@code {"type":..., "data":...}} rather than STOMP: the browser
 * needs no client library, which keeps the dashboard a single dependency-free page.
 */
@Component
public class DashboardSocketHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(DashboardSocketHandler.class);

    /** Buffer limits stop one stalled browser from pinning memory in the analyzer. */
    private static final int SEND_BUFFER_BYTES = 512 * 1024;
    private static final int SEND_TIME_LIMIT_MS = 10_000;

    private final Map<String, WebSocketSession> sessions = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;
    private final ApplicationEventPublisher events;
    private final AtomicLong messagesSent = new AtomicLong();

    public DashboardSocketHandler(ObjectMapper objectMapper, ApplicationEventPublisher events) {
        this.objectMapper = objectMapper;
        this.events = events;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.put(session.getId(), new ConcurrentWebSocketSessionDecorator(session, SEND_TIME_LIMIT_MS, SEND_BUFFER_BYTES));
        log.info("Dashboard connected: {} ({} client(s) attached)", session.getId(), sessions.size());
        events.publishEvent(new DashboardClientConnected(session.getId()));
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session.getId());
        log.info("Dashboard disconnected: {} ({}), {} client(s) remain", session.getId(), status, sessions.size());
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        // The dashboard is read-only; a client frame is only ever a keepalive ping.
        send(session, "pong", Map.of("at", System.currentTimeMillis()));
    }

    public void broadcast(String type, Object payload) {
        if (sessions.isEmpty()) {
            return;
        }
        String frame = encode(type, payload);
        if (frame == null) {
            return;
        }
        sessions.forEach((id, session) -> writeFrame(id, session, frame));
    }

    public void sendTo(String sessionId, String type, Object payload) {
        WebSocketSession session = sessions.get(sessionId);
        if (session != null) {
            send(session, type, payload);
        }
    }

    public int connectedClients() {
        return sessions.size();
    }

    public long messagesSent() {
        return messagesSent.get();
    }

    private void send(WebSocketSession session, String type, Object payload) {
        String frame = encode(type, payload);
        if (frame != null) {
            writeFrame(session.getId(), session, frame);
        }
    }

    private String encode(String type, Object payload) {
        try {
            return objectMapper.writeValueAsString(Map.of("type", type, "data", payload));
        } catch (IOException ex) {
            log.warn("Could not serialise {} frame: {}", type, ex.toString());
            return null;
        }
    }

    private void writeFrame(String sessionId, WebSocketSession session, String frame) {
        if (!session.isOpen()) {
            sessions.remove(sessionId);
            return;
        }
        try {
            session.sendMessage(new TextMessage(frame));
            messagesSent.incrementAndGet();
        } catch (IOException | IllegalStateException ex) {
            log.debug("Dropping dashboard session {}: {}", sessionId, ex.toString());
            sessions.remove(sessionId);
        }
    }

    /** Published when a dashboard attaches so the stats service can send it an immediate snapshot. */
    public record DashboardClientConnected(String sessionId) {
    }
}
