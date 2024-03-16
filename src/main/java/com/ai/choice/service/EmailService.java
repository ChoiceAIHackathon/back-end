package com.ai.choice.service;


import com.ai.choice.enumeration.VerificationType;

public interface EmailService {

    void sendVerificationEmail(String firstName, String email, String verificationUrl, VerificationType verificationType);
}
