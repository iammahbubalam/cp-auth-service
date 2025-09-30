package com.iammahbubalam.cp_auth_service.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
public class UserServiceClient {
    public Mono<Object> createUser(UUID id, String username, String email, String firstName, String lastName) {

    return Mono.empty();}

    public boolean isSuccessResponse(Object response) {
        return true;
    }

    public String getResponseMessage(Object response) {
        return "Success";
    }

    public Mono<Object> updateUser(UUID userId, String username, String email, String firstName, String lastName) {

    return Mono.empty();}
}
