package com.curso.springboot.app.auth.service;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.io.IOException;

public interface JWTService {

  public String create(Authentication auth) throws IOException, java.io.IOException;

  public boolean validate(String token);

  public Claims getClaims(String token);

  public String getUsername(String token);

  public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException, java.io.IOException;

  public String resolve(String token);
}
