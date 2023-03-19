package okta.config;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import com.github.ulisesbocchio.spring.boot.security.saml.bean.SAMLConfigurerBean;

import okta.servces.SAMLUserDetailsServiceImpl;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	   
	 @Value("${saml.keystore.path}")
	    private String keyStorePath;

	    @Value("${saml.keystore.password}")
	    private String keyStorePassword;

	    @Value("${saml.keystore.alias}")
	    private String keyAlias;

	    @Value("${saml.key.password}")
	    private String keyPassword;
	   
	    private SAMLUserDetailsService samlUserDetailsService;
	    
	    public SecurityConfig(SAMLUserDetailsService samlUserDetailsService)
	    {
	    	this.samlUserDetailsService=samlUserDetailsService;
	    }
	    @Bean
	    SAMLConfigurerBean saml() {
	        return new SAMLConfigurerBean();
	    }


	    @Bean
	    public AuthenticationManager authenticationManagerBean() throws Exception {
	        return super.authenticationManagerBean();
	    }
	    //Needed in some cases to prevent infinite loop
	    @Override
	    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
	        auth.parentAuthenticationManager(null);
	    }


	    @Override
	    public void configure(HttpSecurity http) throws Exception {
	        // @formatter:off
	        http.httpBasic()
	                .disable()
	                .csrf()
	                .disable()
	                .anonymous()
	                .and()
	                .apply(saml())
	                .and()
	                .authorizeRequests()
	                .requestMatchers(saml().endpointsMatcher())
	                .permitAll()
	                .and()
	                .authorizeRequests()
	                .anyRequest()
	                .authenticated();
	        // @formatter:on
	    }
	    @Bean
	    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
	      SAMLWebSSOHoKProcessingFilter filter = new SAMLWebSSOHoKProcessingFilter();
	      filter.setAuthenticationManager(authenticationManager());
	      filter.setAuthenticationSuccessHandler(successRedirectHandler());
	      filter.setAuthenticationFailureHandler(authenticationFailureHandler());
	      return filter;
	    }
	    
	    @Bean
	    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
	      SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
	          new SavedRequestAwareAuthenticationSuccessHandler();
	      successRedirectHandler.setDefaultTargetUrl("/home");
	      return successRedirectHandler;
	    }

	    @Bean
	    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
	      return new SimpleUrlAuthenticationFailureHandler();
	    }

	    

	    @Override
	    public void configure(WebSecurity web) throws Exception {
	      web.ignoring().antMatchers("/css/**");
	    }
	   

	    @Bean
	    public SAMLUserDetailsService samlUserDetailsService() {
	      return new SAMLUserDetailsServiceImpl();
	    }
	    
	    @Bean
	    public SAMLContextProvider samlContextProvider() {
            SAMLContextProviderLB samlContextProviderLB = new SAMLContextProviderLB();
            samlContextProviderLB.setScheme("http");
            samlContextProviderLB.setContextPath("/api/idp");
            samlContextProviderLB.setServerName("localhost");
            samlContextProviderLB.setServerPort(6080);
            samlContextProviderLB.setIncludeServerPortInRequestURL(true);
            return samlContextProviderLB;
        }
	    
	    @Bean
	    public MetadataManager metadata() throws MetadataProviderException {
	        List<MetadataProvider> providers = new ArrayList<>();
	        providers.add(new HTTPMetadataProvider("https://idp.example.com/metadata", 5000));
	        CachingMetadataManager metadataManager = new CachingMetadataManager(providers);
	        metadataManager.setDefaultIDP("https://idp.example.com/SSO");
	        return metadataManager;
	    }
	    
	    @Bean
	    public SAMLProcessor samlProcessor() {
	        List<SAMLBinding> bindings = new ArrayList<>();
	        bindings.add(httpRedirectDeflateBinding());
	        bindings.add(httpPostBinding());
	        bindings.add(artifactBinding(parserPool()));
	        bindings.add(paosBinding());
	        return new SAMLProcessorImpl(bindings);
	    }
		private SAMLBinding paosBinding() {
			// TODO Auto-generated method stub
			return null;
		}
		private SAMLBinding artifactBinding(Object parserPool) {
			// TODO Auto-generated method stub
			return null;
		}
		@Bean(initMethod = "initialize")
		public StaticBasicParserPool parserPool() {
		    return new StaticBasicParserPool();
		}
		private SAMLBinding httpPostBinding() {
			// TODO Auto-generated method stub
			return  new HTTPPostBinding((ParserPool) parserPool(), VelocityFactory.getEngine());
		}
		private SAMLBinding httpRedirectDeflateBinding() {
			// TODO Auto-generated method stub
			return null;
		}
		
		    @Bean
		    public KeyManager keyManager() {
		        DefaultResourceLoader loader = new DefaultResourceLoader();
		        Resource storeFile = loader.getResource(keyStorePath);
		        String storePass = keyStorePassword;
		        Map<String, String> passwords = new HashMap<>();
		        passwords.put(keyAlias, keyPassword);
		        String defaultKey = keyAlias;
		        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
		    }
}
