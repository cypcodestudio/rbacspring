package com.cypcode.rbacspring.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.cypcode.rbacspring.entity.User;



@Repository
public interface IUserRepository extends JpaRepository<User, Long> {
    User findUserByUsernameAndPassword(String username, String password);
    
    User findByUsername(String username);
}
