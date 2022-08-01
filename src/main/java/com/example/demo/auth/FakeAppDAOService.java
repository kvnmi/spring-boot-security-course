package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.Security.ApplicationUserRole.STUDENT;

@Repository("fake")
public class FakeAppDAOService implements ApplicationUserDAO {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeAppDAOService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    private List<ApplicationUser> getAppUsers() {
        var appUsers = Lists.newArrayList(
                new ApplicationUser(STUDENT.getAuthorities(),
                        passwordEncoder.encode("password"),
                        "linda",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(STUDENT.getAuthorities(),
                        passwordEncoder.encode("password"),
                        "admin",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(STUDENT.getAuthorities(),
                        passwordEncoder.encode("password"),
                        "trainee",
                        true,
                        true,
                        true,
                        true
                )
        );
        return appUsers;
    }

    @Override
    public Optional<ApplicationUser> selectUserByUsername(String username) {
        return getAppUsers()
                .stream()
                .filter(applicationUser -> username.equalsIgnoreCase(applicationUser.getUsername()))
                .findFirst();
    }
}
