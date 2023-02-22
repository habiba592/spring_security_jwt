package com.spring.evmp.payload.response;

import com.spring.evmp.models.User;

import java.util.List;

public class UserDataResponse {
    private List<User> users;

    public UserDataResponse(List<User> users) {
        this.users = users;
    }

    public List<User> getUsers() {
        return users;
    }

    @Override
    public String toString() {
        return "UserDataResponse{" +
                "users=" + users +
                '}';
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }
}
