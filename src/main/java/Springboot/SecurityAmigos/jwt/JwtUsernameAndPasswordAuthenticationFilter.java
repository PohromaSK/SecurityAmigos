package Springboot.SecurityAmigos.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
/*
This class is intended to intercept login requests to authenticate users.
It probably works with JWT (JSON Web Token), a common method for securely transmitting information
between parties as a JSON object.

JwtUsernameAndPasswordAuthenticationFilter is a subclass of UsernamePasswordAuthenticationFilter,
which is a built-in filter in Spring Security used to process username and password authentication forms.
 */
    private final AuthenticationManager authenticationManager;
    //The AuthenticationManager is a Spring Security interface that is used to authenticate an Authentication object.

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

//This method overrides attemptAuthentication from the UsernamePasswordAuthenticationFilter class.
// It's responsible for processing the authentication request.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try{
            UsernameAndPasswordAuthenticationRequest usernameAndPasswordAuthenticationRequest =
                    /*
                    It first attempts to retrieve the username and password from the request's input stream by using Jackson's ObjectMapper.
                    This is assuming that the login information is sent in the request body as a JSON object.
                     */
                    new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                   usernameAndPasswordAuthenticationRequest.getUsername(),
                    usernameAndPasswordAuthenticationRequest.getPassword()
                    /*
                    It then creates an Authentication object (specifically UsernamePasswordAuthenticationToken) with the provided username and password.
                    This object is not yet authenticated but ready to be passed to AuthenticationManager.
                     */
            );
            Authentication authenticate = authenticationManager.authenticate(authentication);
            /*
            his line instructs the AuthenticationManager to attempt to authenticate the token.
            The AuthenticationManager will use the configured UserDetailsService and PasswordEncoder to validate the username and password.
             */
            return authenticate;
        }catch (IOException e){
            throw new RuntimeException(e);
        }
    }
}
