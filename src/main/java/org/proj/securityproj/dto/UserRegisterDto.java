package org.proj.securityproj.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserRegisterDto {

    @NotBlank(message = "Email не може бути порожнім")
    private String email;

    @NotBlank(message = "Пароль не може бути порожнім")
    @Size(min = 8, message = "Пароль повинен бути не менше 8 символів")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z\\d]).+$",
            message = "Пароль повинен містити великі і малі літери, цифру та спеціальний символ"
    )
    private String password;

    @NotBlank(message = "Підтвердження паролю обов'язкове")
    private String confirmPassword;
}
