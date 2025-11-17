package org.proj.securityproj.dto;

import lombok.Data;

import java.util.List;

@Data
public class RecaptchaResponse {
    private boolean success;
    private List<String> errorCodes;
}
