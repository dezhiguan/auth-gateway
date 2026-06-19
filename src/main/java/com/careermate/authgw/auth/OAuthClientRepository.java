package com.careermate.authgw.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class OAuthClientRepository {

    private static final TypeReference<Set<String>> STRING_SET = new TypeReference<>() {
    };

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public OAuthClientRepository(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public Optional<OAuthClient> findById(String clientId) {
        List<OAuthClient> clients = jdbcTemplate.query("""
                        SELECT client_id, client_name, auth_method, jwks_uri,
                               allowed_grant_types::text AS allowed_grant_types,
                               allowed_audiences::text AS allowed_audiences,
                               allowed_scopes::text AS allowed_scopes,
                               status
                        FROM oauth_clients
                        WHERE client_id = ?
                        """,
                (rs, rowNum) -> mapClient(rs),
                clientId);
        return clients.stream().findFirst();
    }

    private OAuthClient mapClient(ResultSet rs) throws SQLException {
        try {
            return new OAuthClient(
                    rs.getString("client_id"),
                    rs.getString("client_name"),
                    rs.getString("auth_method"),
                    rs.getString("jwks_uri"),
                    objectMapper.readValue(rs.getString("allowed_grant_types"), STRING_SET),
                    objectMapper.readValue(rs.getString("allowed_audiences"), STRING_SET),
                    objectMapper.readValue(rs.getString("allowed_scopes"), STRING_SET),
                    rs.getString("status"));
        } catch (Exception ex) {
            throw new SQLException("Failed to parse oauth client JSON fields", ex);
        }
    }
}
