package com.example.app.app.location.domain.mapper;

import com.example.app.app.location.domain.dto.AddressDto;
import com.example.app.app.location.domain.entity.AddressEntity;
import com.example.app.common.domain.mapper.GenericMapper;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.time.LocalDateTime;

@Mapper(componentModel = "spring", imports = {LocalDateTime.class})
public interface AddressMapper extends GenericMapper<AddressEntity, AddressDto.Address> {
    @Override
    @Mapping(target = "cityByCityId", ignore = true)
    AddressDto.Address mapToDto(AddressEntity entity);

    @Mapping(target = "addressId", ignore = true)
    @Mapping(target = "lastUpdate", expression = "java(LocalDateTime.now())")
    @Mapping(target = "cityByCityId", ignore = true)
    AddressEntity mapToEntity(AddressDto.AddressRequest dto);
}
