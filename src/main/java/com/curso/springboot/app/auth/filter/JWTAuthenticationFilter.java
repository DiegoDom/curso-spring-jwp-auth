package com.curso.springboot.app.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.curso.springboot.app.auth.service.JWTService;
import com.curso.springboot.app.auth.service.JWTServiceImpl;
import com.curso.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private AuthenticationManager authenticationManager;
  private JWTService jwtService;

  public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
    this.authenticationManager = authenticationManager;
    setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));

    this.jwtService = jwtService;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException {

    String username = obtainUsername(request);
    username = (username != null) ? username : null;
    String password = obtainPassword(request);
    password = (password != null) ? password : null;

    if (username != null && password != null) {
      logger.info("Username desde request paratemer (formdata): " + username);
      logger.info("Password desde request paratemer (formdata): " + password);
    } else {
      Usuario user = null;
      try {
        user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);

        username = user.getUsername();
        password = user.getPassword();

        logger.info("Username desde request InputStream (raw): " + username);
        logger.info("Password desde request InputStream (raw): " + password);

      } catch (StreamReadException e) {
        e.printStackTrace();
      } catch (DatabindException e) {
        e.printStackTrace();
      } catch (IOException e) {
        e.printStackTrace();
      }

    }
    username = username.trim();
    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

    return authenticationManager.authenticate(authToken);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {

    String token = jwtService.create(authResult);

    response.addHeader(JWTServiceImpl.HEADER_STRING, JWTServiceImpl.TOKEN_PREFIX + token);

    Map<String, Object> body = new HashMap<String, Object>();

    body.put("token", token);
    body.put("user", (User) authResult.getPrincipal());
    body.put("estatus", "success");
    body.put("mensaje", String.format("Sesión iniciada con éxito. Bienvenido %s", authResult.getName()));

    response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    response.setStatus(200);
    response.setContentType("application/json");
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {

    Map<String, Object> body = new HashMap<String, Object>();
    body.put("estatus", "fail");
    body.put("mensaje", "Error al iniciar sesión, verifica tus credenciales.");
    body.put("error", failed.getMessage());

    response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    response.setStatus(401);
    response.setContentType("application/json");

  }

}
