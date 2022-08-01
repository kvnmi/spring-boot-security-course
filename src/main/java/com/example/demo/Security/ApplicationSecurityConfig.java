package com.example.demo.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.Security.AppUserPermission.COURSE_WRITE;
import static com.example.demo.Security.AppUserPermission.STUDENT_WRITE;
import static com.example.demo.Security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //Specify routes t0 exclude from basic auth
                .antMatchers("/api/**").hasAnyRole(ADMIN.name(), STUDENT.name())
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermissions(), COURSE_WRITE.name()) // Only users with student read or course read permissions
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermissions(), COURSE_WRITE.name())
                // .antMatchers(HttpMethod.POST, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermissions(), COURSE_WRITE.name())
                // .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name()) // only admin members can reach this endpoint;
                .anyRequest()//all other requests made to this server
                .authenticated() // should be authenticated
                .and()
                .httpBasic(); // basic security is the authentication method to be used
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        var user = User.builder()
                .username("annasmith")
                //.roles(STUDENT.name())
                .authorities(STUDENT.getAuthorities())
                .password(passwordEncoder.encode("password"))
                .build();

        var admin = User.builder()
                .username("Sage")
                .password(passwordEncoder.encode("admin"))
                .authorities(ADMIN.getAuthorities())
                .build();
        var adminTrainee = User.builder()
                .username("trainee")
                .password(passwordEncoder.encode("admin"))
                //.roles(ADMIN_TRAINEE.name())
                .authorities(ADMIN_TRAINEE.getAuthorities())
                .build();


        return new InMemoryUserDetailsManager(user, admin, adminTrainee);
    }
}
