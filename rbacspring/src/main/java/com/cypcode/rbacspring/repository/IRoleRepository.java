package com.cypcode.rbacspring.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.cypcode.rbacspring.entity.Role;



@Repository
public interface IRoleRepository extends JpaRepository<Role, Long>{
	Role findByName(String name);

}
