package com.spring.evmp.security.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;

import com.spring.evmp.services.UserDetailsImpl;
import io.jsonwebtoken.*;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${com.spring.jwtSecret}")
  private String jwtSecret;

  @Value("${com.spring.jwtExpirationMs}")
  private int jwtExpirationMs;

  @Value("${com.spring.jwtTokenName}")
  private String jwtTokenName;

  public String getJwtFromToken(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7);
    }
    return null;
  }

  public String generateJwtToken(UserDetailsImpl userPrincipal, List<String> roles ) {
    String jwtToken = generateTokenFromUsername(userPrincipal.getUsername(), roles);
    /*ResponseCookie cookie = ResponseCookie.from(jwtTokenName, jwtToken).path("/api")
            .maxAge(24 * 60 * 60).httpOnly(true).build();*/
    return "Bearer "+ jwtToken;

  }

/*
  public ResponseCookie getCleanJwtCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
    return cookie;
  }
*/

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
  }

  public List<String> getRolesFromJwtToken(String token) {
    Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
    List<String> roles = (List<String>) claims.get("role");
    return roles;
  }



  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }

  public String generateTokenFromUsername(String username, List<String> roles) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("role", roles);
    return Jwts.builder()
            .setClaims(claims)
        .setSubject(username)
        .setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(SignatureAlgorithm.HS512, jwtSecret)
        .compact();
   /* return Jwts.builder().setClaims(claims).setSubject(subject).setId(ID+"").
            setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY*1000)).
            signWith(SignatureAlgorithm.HS512, secret).compact();*/
  }
}
