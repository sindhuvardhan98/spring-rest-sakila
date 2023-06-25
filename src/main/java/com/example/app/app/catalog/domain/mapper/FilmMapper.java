package com.example.app.app.catalog.domain.mapper;

import com.example.app.app.catalog.domain.dto.FilmDto;
import com.example.app.app.catalog.domain.entity.FilmEntity;
import com.example.app.common.domain.mapper.GenericMapper;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.time.LocalDateTime;

@Mapper(componentModel = "spring", imports = {LocalDateTime.class})
public interface FilmMapper extends GenericMapper<FilmEntity, FilmDto.Film> {
    @Override
    @Mapping(target = "languageByLanguageId", ignore = true)
    @Mapping(target = "languageByOriginalLanguageId", ignore = true)
    FilmDto.Film mapToDto(FilmEntity entity);

    @Mapping(target = "filmId", ignore = true)
    @Mapping(target = "lastUpdate", expression = "java(LocalDateTime.now())")
    @Mapping(target = "languageByLanguageId", ignore = true)
    @Mapping(target = "languageByOriginalLanguageId", ignore = true)
    FilmEntity mapToEntity(FilmDto.FilmRequest dto);
}
