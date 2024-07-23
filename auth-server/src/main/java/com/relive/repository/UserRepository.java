package com.relive.repository;

import com.relive.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
public interface UserRepository extends JpaRepository<User, Long> {

    User findUserByUsername(String username);
}
