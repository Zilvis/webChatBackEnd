package dev.zilvis.baseAppWithSecurity.payLoad.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor

public class UserInfoResponse {
    private Long id;
    private String username;
    private String nickName;
    private List<String> roles;
    private String JwtToken;

    public UserInfoResponse(Long id, String username, String nickName) {
        this.id = id;
        this.username = username;
        this.nickName = nickName;
    }
}
