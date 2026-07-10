package com.careermate.authgw.auth;

/** 协议版本单一真源。登录比对与补签校验共用，避免版本号散落多处。 */
public final class TermsPolicy {

    /** 当前生效的协议版本；协议正文更新时同步递增，并同步前端 legalDocs 与后端此常量。 */
    public static final String CURRENT_VERSION = "1.0";

    private TermsPolicy() {}

    public static boolean isCurrent(String version) {
        return CURRENT_VERSION.equals(version);
    }
}
