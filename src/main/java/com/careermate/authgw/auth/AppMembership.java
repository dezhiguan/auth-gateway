package com.careermate.authgw.auth;

/** 用户对某个 App（careermate / ragforge）的准入与应用内角色。 */
public record AppMembership(
        long userId,
        String app,
        String role,
        String status) {
}
