package dev.zilvis.baseAppWithSecurity.payLoad.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SignupRequest {
    @NotBlank
    @Size(min = 3, max = 50)
    @Email(message = "Neteisingas elektroninis paštas")
    private String username; // Email

    private Set<String> role;

    @NotBlank
    @Size(min = 6, max = 40)
    private String password;
}