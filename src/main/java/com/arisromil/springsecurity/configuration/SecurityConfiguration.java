package com.arisromil.springsecurity.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain1(HttpSecurity http) throws
            Exception {
               http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/", "/welcome").permitAll()
                        .requestMatchers("/authenticated").hasRole("ADMIN")
                        .anyRequest().denyAll()
                )

               .rememberMe((remember) -> remember
                        .rememberMeParameter("remember-me")
                        .key("uniqueAndSecretKey")
                        .tokenValiditySeconds(1000)
                        .rememberMeCookieName("rememberloginnardone")
                        .rememberMeParameter("remember-me")
                       )
                // using customized login html page
                .formLogin((form) -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/authenticated")
                        .permitAll()
                        .failureHandler(authenticationFailureHandler())
                .loginPage("/login")
                .permitAll()

        )
                .logout((logout) -> logout
                        .logoutSuccessUrl("/welcome")
                        .deleteCookies("JSESSIONID")
                        .invalidateHttpSession(true)
                        .permitAll()
                );
        return http.build();
    }
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("userpassw"))
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("adminpassw"))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }
    @Bean
    public static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }



}
