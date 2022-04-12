package com.curso.springboot.app;

import com.curso.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.curso.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.curso.springboot.app.auth.service.JWTService;

// import javax.sql.DataSource;

// import com.curso.springboot.app.auth.handler.LoginSuccessHandler;
import com.curso.springboot.app.models.service.JpaUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  /*
   * @Autowired
   * private DataSource dataSource;
   */

  @Autowired
  private JpaUserDetailsService userDetailsService;

  @Autowired
  private JWTService jwtService;

  @Autowired
  public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {

    builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);

    /*
     * builder.jdbcAuthentication().dataSource(dataSource).passwordEncoder(
     * passwordEncoder)
     * .usersByUsernameQuery("select username, password, enabled from users where username=?"
     * )
     * .authoritiesByUsernameQuery(
     * "select u.username, a.authority from authorities a inner join users u on (a.user_id = u.id) where u.username=?"
     * );
     */

    /*
     * PasswordEncoder encoder = this.passwordEncoder;
     * // (encoder::encode) === (password -> encoder.encode(password));
     * UserBuilder users = User.builder().passwordEncoder(encoder::encode);
     * 
     * builder.inMemoryAuthentication()
     * .withUser(users.username("admin").password("admin").roles("ADMIN", "USER"))
     * .withUser(users.username("diego").password("admin").roles("USER"));
     */

  }

  // @Autowired
  // private LoginSuccessHandler successHandler;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers(
            "/",
            "/css/**",
            "/js/**",
            "/images/**",
            "/fonts/**",
            "/listar",
            "/api",
            "/api/listar",
            "/locale")
        .permitAll()
        .anyRequest().authenticated()
        /*
         * .and()
         * .formLogin()
         * .successHandler(successHandler)
         * .loginPage("/login")
         * .permitAll()
         * .and()
         * .logout().permitAll()
         * .and()
         * .exceptionHandling().accessDeniedPage("/error_403")
         */
        .and()
        .addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService))
        .addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService))
        .csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
  }

}
