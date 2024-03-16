package com.ai.choice.repository;
import com.ai.choice.domain.Users;
import com.ai.choice.dto.UserDTO;
import com.ai.choice.form.UpdateForm;
import org.springframework.web.multipart.MultipartFile;

import java.util.Collection;

public interface UserRepository <T extends Users>{
    //    Basic CRUD Operations
    T create(T data);
    Collection<T> list(int page, int pageSize);
    T get (Long id);
    T update(T data);
    Boolean delete (Long id);

    Users getUserByEmail(String email);
    void sendVerificationCode(UserDTO user);

    Users verifyCode(String email, String code);

    void resetPassword(String email);

    T verifyPasswordKey(String key);

    void renewPassword(String key, String password, String confirmPassword);

    T verifyAccountKey(String key);

    T updateUserDetails(UpdateForm user);

    void updatePassword(Long id, String currentPassword, String newPassword, String confirmNewPassword);

    void updateAccountSettings(Long userId, Boolean enabled, Boolean notLocked);

   // User toggleMfa(String email);

    void updateImage(UserDTO user, MultipartFile image);
}