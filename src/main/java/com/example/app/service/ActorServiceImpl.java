package com.example.app.service;

import com.example.app.exception.ResourceNotFoundException;
import com.example.app.model.internal.ActorDetailModel;
import com.example.app.model.internal.ActorModel;
import com.example.app.model.mapping.mapper.ActorMapper;
import com.example.app.model.request.ActorRequestModel;
import com.example.app.repository.ActorRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class ActorServiceImpl implements ActorService {
    private final ActorRepository actorRepository;
    private final ActorMapper actorMapper;

    @Override
    public List<ActorModel> getAllActors() {
        var list = actorRepository.findAll();
        return actorMapper.mapToDtoList(list);
    }

    @Override
    public Optional<ActorModel> getActorById(String id) {
        var entity = actorRepository.findById(Integer.valueOf(id)).orElseThrow(() ->
                new ResourceNotFoundException("Actor not found with id '" + id + "'"));
        return Optional.of(actorMapper.mapToDto(entity));
    }

    @Override
    public List<ActorDetailModel> getAllActorsDetail() {
        return actorRepository.findAllActorsDetail();
    }

    @Override
    public Optional<ActorDetailModel> getActorDetailById(String id) {
        var model = actorRepository.findActorDetailById(Integer.valueOf(id));
        if (model.isEmpty()) {
            throw new ResourceNotFoundException("Actor not found with id '" + id + "'");
        }
        return model;
    }

    @Override
    public List<ActorModel> findActorByName(String name) {
        var list = actorRepository.findActorByName(name);
        return actorMapper.mapToDtoList(list);
    }

    @Override
    public ActorModel addActor(ActorRequestModel model) {
        var entity = actorMapper.mapToEntity(model);
        var savedEntity = actorRepository.save(entity);
        return actorMapper.mapToDto(savedEntity);
    }

    @Override
    @Transactional
    public ActorModel updateActor(String id, ActorRequestModel model) {
        var entity = actorRepository.findById(Integer.valueOf(id)).orElseThrow(() ->
                new ResourceNotFoundException("Actor not found with id '" + id + "'"));
        entity.update(actorMapper.mapToEntity(model));
        return actorMapper.mapToDto(entity);
    }

    @Override
    public void deleteActorById(String id) {
        actorRepository.deleteById(Integer.valueOf(id));
    }
}
