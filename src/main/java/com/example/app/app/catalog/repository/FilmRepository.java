package com.example.app.app.catalog.repository;

import com.example.app.app.catalog.domain.entity.FilmEntity;
import com.example.app.app.catalog.repository.custom.CustomFilmRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FilmRepository extends JpaRepository<FilmEntity, Integer>, CustomFilmRepository {
}