package com.spring.evmp.payload.response;

import com.spring.evmp.models.User;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserDataResponse {
    private List<?> users;

    public UserDataResponse(List<?> users) {
        this.users = users;
    }

    @Override
    public String toString() {
        return "Response is{" +
                "response=" + users +
                '}';
    }

}
