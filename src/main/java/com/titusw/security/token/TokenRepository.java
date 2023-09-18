package com.titusw.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, String> {

    @Query("""
        SELECT t FROM Token t inner join User u on t.user.ksuid = u.ksuid
        WHERE u.ksuid = :userKsuid and (t.expired = false or t.revoked = false)
    """)
    List<Token> findAllValidTokensByUser(String userKsuid);

    Optional<Token> findByToken(String s);
}
