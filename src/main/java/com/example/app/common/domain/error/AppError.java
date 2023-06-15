package com.example.app.common.domain.error;

import com.example.app.common.constant.ErrorLevel;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AppError {
    private String code;
    private ErrorLevel level;
    private String phrase;
    private String requestMethod;
    private String requestUrl;
    private Instant timestamp;
}