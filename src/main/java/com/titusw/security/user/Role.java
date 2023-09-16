package com.titusw.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.titusw.security.user.Permission.*;

@RequiredArgsConstructor
public enum Role {

    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_DELETE,
                    ADMIN_CREATE,
                    MANAGEMENT_READ,
                    MANAGEMENT_UPDATE,
                    MANAGEMENT_DELETE,
                    MANAGEMENT_CREATE
            )
    ),
    MANAGER(
            Set.of(
                    MANAGEMENT_READ,
                    MANAGEMENT_UPDATE,
                    MANAGEMENT_DELETE,
                    MANAGEMENT_CREATE
            )
    )
    ;

    @Getter
    private final Set<Permission> permissions;

//    public List<SimpleGrantedAuthority>
}
