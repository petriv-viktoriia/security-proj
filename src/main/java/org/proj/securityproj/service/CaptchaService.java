package org.proj.securityproj.service;


import lombok.RequiredArgsConstructor;
import org.proj.securityproj.dto.RecaptchaResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;


@RequiredArgsConstructor
@Service
public class CaptchaService {

    @Value("${recaptcha.secretKey}")
    private String secretKey;

    @Value("${recaptcha.url}")
    private String recaptchaUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    public boolean verifyCaptcha(String captchaResponse) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("secret", secretKey);
        params.add("response", captchaResponse);

        RecaptchaResponse response = restTemplate.postForObject(
                recaptchaUrl,
                params,
                RecaptchaResponse.class
        );

        return response != null && response.isSuccess();
    }
}
