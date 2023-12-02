package com.sergioferlg.security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "a87f946d645f76352fec5b3f28af6efc762b39e03354ba7b6652b32fcdb94254";    //generated on a webpage

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);   //decoded in base64
        return Keys.hmacShaKeyFor(keyBytes);                    //using algorithm
    }

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(
            String token,                                       //Token to get all claims
            Function<Claims, T> claimResolver                   //A function will be passed later to get the claim we want
    ){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    /***
     *
     * @param extraClaims to be inserted in token
     * @param userDetails as of part of Spring framework with the details for user
     * @return A new token generated with claims and user details
     */
    public String generateToken(
            Map<String, Object> extraClaims,                   //Pass authorities, extra info
            UserDetails userDetails
    ){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())                                      //This is the user info we are using as pointing (this case the user email
                .setIssuedAt(new Date(System.currentTimeMillis()))                          //when this claim was created to check if token is valid or not
                .setExpiration(new Date(System.currentTimeMillis() + (1000*60*24)))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /***
     *
     * @param userDetails as of part of Spring framework with the details for user
     * @return A new token generated with only user details
     */
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        //Check if token belongs to the user
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration (String token){
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
