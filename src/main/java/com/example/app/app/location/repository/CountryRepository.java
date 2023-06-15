package com.example.app.app.location.repository;

import com.example.app.app.location.domain.entity.CountryEntity;
import com.example.app.app.location.repository.custom.CustomCountryRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CountryRepository extends JpaRepository<CountryEntity, Integer>, CustomCountryRepository {
}