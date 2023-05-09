package com.example.backend.service;

import com.example.backend.entity.User;
import com.example.backend.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    // 보안 키 (230410 수정)
    private static final String SECRET_KEY = "CL2xeP3cZ0MDZQDmuWeHPajwAJSPwtBk0JI5t6KCdGnK6ckXxx";

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public String login(String email, String password, HttpServletResponse response) throws AuthenticationException {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (!user.getPassword().equals(password)) {
                throw new BadCredentialsException("Invalid email or password");
            }
            String token = createToken(email);
            Cookie cookie = new Cookie("token", token);
            cookie.setHttpOnly(true);
            cookie.setMaxAge(24 * 60 * 60); // 쿠키 만료 시간 설정 (예: 24시간)
            response.addCookie(cookie);
            return token;
        }
        throw new BadCredentialsException("Invalid email or password");
    }

    private String createToken(String email) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + 1000 * 60 * 60 * 10); // 10 hours
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public String getEmailFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    public Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
}