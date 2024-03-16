package com.ai.choice.utils;

import com.ai.choice.domain.UserPrincipal;
import com.ai.choice.dto.UserDTO;
import org.springframework.security.core.Authentication;

public class UserUtils {

    public static UserDTO getAuthenticatedUser(Authentication authentication){
        return ((UserDTO) authentication.getPrincipal());
    }

    public static UserDTO getLoggedInUser(Authentication authentication){
        return ((UserPrincipal) authentication.getPrincipal()).getUser();
    }
}
