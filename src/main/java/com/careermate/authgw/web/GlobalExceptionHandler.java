package com.careermate.authgw.web;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 兜底框架级异常，统一返回 {error, message} 结构的友好 JSON，避免 Spring 默认错误页
 * 直接把 {timestamp, status, path} 裸露给客户端。
 *
 * <p>仅处理明确的请求格式类异常；不设 Exception 全捕获，以免掩盖真实 500 便于排障。
 * 各控制器自身的 @ExceptionHandler(AuthException/SmsException) 优先级更高，此处不干预。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** 请求体缺失或无法解析（如 DELETE 不带 body、JSON 语法错误）。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleNotReadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "REQUEST_BODY_INVALID", "message", "请求体缺失或格式不正确"));
    }

    /** Content-Type 不受支持（如缺失或非 application/json）。 */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> handleUnsupportedMedia(HttpMediaTypeNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(Map.of("error", "UNSUPPORTED_MEDIA_TYPE", "message", "请求 Content-Type 不受支持，请使用 application/json"));
    }
}
