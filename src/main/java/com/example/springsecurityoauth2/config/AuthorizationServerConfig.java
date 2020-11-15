package com.example.springsecurityoauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * 授权服务配置
 * 1、授权码模式：最常见，最常用，可用于第三方应用授权、SSO登录实现等
 * 2、密码模式：自己本身有一套用户体系，在认证时需要带上自己的用户名和密码，以及客户端的client_id,client_secret。
*             此时，accessToken所包含的权限是用户本身的权限，而不是客户端的权限
 * 3、简单模式： 不常用
 * 4、客户端模式：一般用于后台服务接口间的认证 。没有用户的概念，直接与认证服务器交互，用配置中的客户端信息去申请accessToken，
 *              客户端有自己的client_id,client_secret对应于用户的username,password，而客户端也拥有自己的authorities，
 *              当采取client模式认证时，对应的权限也就是客户端自己的authorities
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * 注入客户端详情服务
     */
    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 用户认证信息
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user_1").password(passwordEncoder.encode("123456")).authorities("USER").build());
        manager.createUser(User.withUsername("user_2").password(passwordEncoder.encode("123456")).authorities("USER").build());
        return manager;
    }

    /**
     * 授权码模式
     * 授权码模式的存储策略（内存、JDBC）
     * @return
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(){
        return  new InMemoryAuthorizationCodeServices();
    }
    /**
     * 令牌存储策略(内存、JWT、JDBC、Redis)
     * @return
     */
    @Bean
    public TokenStore tokenStore(){
        return new InMemoryTokenStore();
    }

    public AuthorizationServerConfig() {
        super();
    }

    /**
     * 令牌访问端点安全策略设置
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")//  /oauth/token_key 公开
                .checkTokenAccess("permitAll()")// /oauth/check_token 公开
                .allowFormAuthenticationForClients();//允许表单认证，申请令牌

    }

    /**
     * 客户端详情配置
     * 内存、jdbc等
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()        //基于内存存储
                .withClient("app")         //客户端Id
                .secret(passwordEncoder.encode("123456"))  //客户端密码
                .authorizedGrantTypes("authorization_code","password","refresh_token","implicit","client_credentials")     //授权模式 5种
                .scopes("all")          //允许的授权范围
                .resourceIds("res1")    //资源列表
                .autoApprove(false)     //false 跳转到授权页面
                .redirectUris("http://www.baidu.com"); //客户端回调地址.
    }

    /**
     * 令牌访问端点设置
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                //.authenticationManager(authenticationManager)// 认证管理器 用于密码模式
                .authorizationCodeServices(authorizationCodeServices())//授权码服务 授权码模式需要
                .userDetailsService(userDetailsService()) //用户身份认证
                .tokenServices(tokenServices())//令牌管理服务
                .allowedTokenEndpointRequestMethods(HttpMethod.POST,HttpMethod.GET);//允许提交方式
    }

    /**
     * 令牌管理服务
     * @return
     */
    @Bean
    public AuthorizationServerTokenServices tokenServices(){
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());//令牌存储策略
        defaultTokenServices.setClientDetailsService(clientDetailsService);//客户端信息服务
        defaultTokenServices.setSupportRefreshToken(true);//是否产生刷新令牌
        defaultTokenServices.setAccessTokenValiditySeconds(7200);//令牌默认有效期 2个小时
        defaultTokenServices.setRefreshTokenValiditySeconds(259200);//刷新令牌默认有效期 3天
        return  defaultTokenServices;
    }
}
