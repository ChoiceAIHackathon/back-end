package com.ai.choice.dtomapper;


import com.ai.choice.domain.Role;
import com.ai.choice.domain.Users;
import com.ai.choice.dto.UserDTO;
import org.springframework.beans.BeanUtils;

public class UserDTOMapper {
    public static UserDTO fromUser(Users user){
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        return userDTO;
    }
    public static UserDTO fromUser(Users user, Role role){
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        userDTO.setRoleName(role.getName());
        userDTO.setPermission(role.getPermission());
        return userDTO;
    }

    public static Users toUser(UserDTO userDTO){
        Users user = new Users();
        BeanUtils.copyProperties(userDTO, user);
        return user;
    }

}