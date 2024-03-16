package com.ai.choice.repository;


import com.ai.choice.domain.UserEvent;
import com.ai.choice.enumeration.EventType;

import java.util.Collection;

public interface EventRepository {

    Collection<UserEvent> getEventsByUserId(Long userId);
    void addUserEvent(String email, EventType eventType, String device, String ipAddress);

    void addUserEvent(Long userId, EventType eventType, String device, String ipAddress);
}
