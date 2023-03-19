package okta.servces;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService{


	@Override
	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		  String userID = credential.getNameID().getValue();
	        List<GrantedAuthority> authorities = new ArrayList<>();

	        // Extract custom attributes from SAML response
	        List<Attribute> attributes = credential.getAttributes();
	        for (Attribute attribute : attributes) {
	            if (attribute.getName().equals("roles")) {
	               
	            }
	        }

	        // Create a new UserDetails object with the extracted data
	        NameID nameID ;
	        UserDetails userDetails = new org.springframework.security.core.userdetails.User(userID, "", authorities);
	        return userDetails;
	}
}
