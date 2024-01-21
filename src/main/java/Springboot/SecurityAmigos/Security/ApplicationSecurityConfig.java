package Springboot.SecurityAmigos.Security;

import Springboot.SecurityAmigos.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import Springboot.SecurityAmigos.Security.ApplicationUserRole;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;

import java.util.concurrent.TimeUnit;

import static Springboot.SecurityAmigos.Security.ApplicationUserRole.*;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity       //to be able to use PreAuthorize in methods in Controller
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;                            //you need it to encode passwords
    private final ApplicationUserService applicationUserService;
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
 /*  //You can persist the CsrfToken in a cookie to support a JavaScript-based application using the CookieCsrfTokenRepository.
The CookieCsrfTokenRepository writes to a cookie named XSRF-TOKEN and reads it from an HTTP request
header named X-XSRF-TOKEN or the request parameter _csrf by default. These defaults come from Angular and its predecessor AngularJS.

                .csrf((csrf) -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )*/
  /*              .csrf(Customizer.withDefaults()   //its defending by defau. not more is necessary for basic csrf
                )*/
                .csrf().disable()            //we need it if we dont have solve stuff around the token
                .authorizeHttpRequests((authorize) -> authorize
                        //position of those requests really matter..its stream...so filtering one by one. ORDER IMPORTANT
                        .requestMatchers("/", "/index", "/css/*", "/js/*").permitAll()
                        .requestMatchers("/api/**").hasRole(STUDENT.name())
                        .anyRequest().authenticated())
                .formLogin((formLog) -> formLog
                        .loginPage("/login")
                        .permitAll()
                        .defaultSuccessUrl("/courses", true)
                        .passwordParameter("password") //the same as in html id
                        .usernameParameter("username"))//the same as in html id
                .rememberMe((httpSecurityRememberMeConfigurer -> httpSecurityRememberMeConfigurer
                        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                        .key("somethingverysecured")//the key how they hash info about cookie
                        .rememberMeParameter("remember-me")))//the same as in html id
                     //change default session to 2weeks, you can adjust it as you see above
                .logout((httpSecurityLogoutConfigurer) -> httpSecurityLogoutConfigurer
                                .logoutUrl("/logout")
                                .clearAuthentication(true)
                                .invalidateHttpSession(true)
                                .deleteCookies("JSESSIONID")
                                .logoutSuccessUrl("/login")
                        /*
                        NOTES:
                        Dont forget dependency on thymeleaf(spring), html files in templates,
                         */
                );

        return httpSecurity.build();

    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);   //decodePassword
        provider.setUserDetailsService(applicationUserService);
        return  provider;
    }

  /*  @Bean    -- not used when we have database Authenticaton
    protected UserDetailsService userDetailsService(){
        UserDetails lukinko = User.builder()
                .username("lukinko")
                .password(passwordEncoder.encode("lorenc"))          //encode password
//                .roles(ApplicationUserRole.STUDENT.name())   //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails linda =User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//                .roles(ApplicationUserRole.ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser =User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//                .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(
                lukinko,
                linda,
                tomUser
        )
    }*/
}
