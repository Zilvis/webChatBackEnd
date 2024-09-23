package dev.zilvis.baseAppWithSecurity.payLoad.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {
    @NotBlank
    @Size(min = 3, max = 50)
    @Email
    private String username; // Email

    @NotBlank
    private String password;
}
