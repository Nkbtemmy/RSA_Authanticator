package com.imanzi.rsa_authanticator.config;

import io.swagger.v3.oas.models.tags.Tag;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;

import java.util.Collections;
import java.util.List;

@Configuration
public class SwaggerConfig {
    @Value("${springdoc.api-docs.version}")
    private String apiDocumentVersion;
    @Value("${spring.application.name}")
    private String appName;

    @Bean
    OpenAPI customOpenAPI() {
        return new OpenAPI()
//                .addServersItem(new Server().url("https://marketplace.onrender.com"))
                .info(new Info()
                        .title(appName)
                        .version(apiDocumentVersion)
                        .description("This is the online marketplace management API"))
                .components(new Components().addSecuritySchemes("Bearer", apiKeySecuritySchema()));
    }

    public SecurityScheme apiKeySecuritySchema() {
        return new SecurityScheme()
                .name("Authorization")
                .description("Access token")
                .in(SecurityScheme.In.HEADER)
                .type(SecurityScheme.Type.APIKEY)
                .bearerFormat("Bearer");
    }
}

@Component
class GlobalHeaderAdder implements OperationCustomizer {
    @Override
    public Operation customize(Operation operation, HandlerMethod handlerMethod) {
        operation.addSecurityItem(new SecurityRequirement().addList("Bearer"));
        List<io.swagger.v3.oas.models.parameters.Parameter> parameterList = operation.getParameters();
        if (parameterList != null && !parameterList.isEmpty()) {
            Collections.rotate(parameterList, 1);
        }
        return operation;
    }
}
