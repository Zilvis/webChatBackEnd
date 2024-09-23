package dev.zilvis.baseAppWithSecurity.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import dev.zilvis.baseAppWithSecurity.enums.ERole;
import dev.zilvis.baseAppWithSecurity.jwt.JwtUtils;
import dev.zilvis.baseAppWithSecurity.models.Role;
import dev.zilvis.baseAppWithSecurity.models.User;
import dev.zilvis.baseAppWithSecurity.payLoad.request.LoginRequest;
import dev.zilvis.baseAppWithSecurity.payLoad.request.SignupRequest;
import dev.zilvis.baseAppWithSecurity.payLoad.response.MessageResponse;
import dev.zilvis.baseAppWithSecurity.payLoad.response.UserInfoResponse;
import dev.zilvis.baseAppWithSecurity.repository.RoleRepository;
import dev.zilvis.baseAppWithSecurity.repository.UserRepository;
import dev.zilvis.baseAppWithSecurity.services.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;



    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());


        return ResponseEntity.ok(new UserInfoResponse(userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getNickName(),
                roles,
                jwtToken));
    }


    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Klaida: Elektroninis paštas jau užimtas!"));
        }

        User user = new User(signUpRequest.getUsername(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Klaida: Rolė nerasta."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Klaida: Rolė nerasta."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Klaida: Rolė nerasta."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Klaida: Rolė nerasta."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Registracija sėkminga!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("Jūs buvote atjungtas!"));
    }

    @PostMapping("/check")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> validateAdminToken(@RequestHeader("Authorization") String token) {
        return new ResponseEntity<>("Hello World!", HttpStatus.OK);
    }

    @PostMapping("/check2")
    @PreAuthorize("hasRole('USER') || hasRole('ADMIN')")
    public ResponseEntity<?> validateUserToken(@RequestHeader("Authorization") String token) {
        return new ResponseEntity<>("Hello World!", HttpStatus.OK);
    }

    @PostMapping("/getUserName")
    public ResponseEntity<?> sendMessage(HttpServletRequest request) {
        String token = jwtUtils.getJwtFromCookies(request);
        String senderUsername = jwtUtils.getUserNameFromJwtToken(token);
        return ResponseEntity.ok(senderUsername);
    }
}