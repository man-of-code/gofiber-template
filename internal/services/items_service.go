package services

import (
	"errors"

	"gofiber_template/internal/models"
	"gorm.io/gorm"
)

var ErrItemNotFound = errors.New("item not found")

type ItemsService struct {
	DB *gorm.DB
}

func NewItemsService(db *gorm.DB) *ItemsService {
	return &ItemsService{DB: db}
}

type PaginatedItems struct {
	Items      []models.Item
	Total      int64
	Page       int
	Limit      int
	TotalPages int64
}

func (s *ItemsService) List(page, limit int) (*PaginatedItems, error) {
	offset := (page - 1) * limit
	var items []models.Item
	var total int64
	if err := s.DB.Model(&models.Item{}).Count(&total).Error; err != nil {
		return nil, err
	}
	if err := s.DB.Offset(offset).Limit(limit).Find(&items).Error; err != nil {
		return nil, err
	}
	return &PaginatedItems{
		Items:      items,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: (total + int64(limit) - 1) / int64(limit),
	}, nil
}

func (s *ItemsService) Get(id uint) (*models.Item, error) {
	var item models.Item
	if err := s.DB.First(&item, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrItemNotFound
		}
		return nil, err
	}
	return &item, nil
}

func (s *ItemsService) Create(name string) (*models.Item, error) {
	item := models.Item{Name: name}
	if err := s.DB.Create(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ItemsService) Update(id uint, name string) (*models.Item, error) {
	var item models.Item
	if err := s.DB.First(&item, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrItemNotFound
		}
		return nil, err
	}
	item.Name = name
	if err := s.DB.Save(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ItemsService) Delete(id uint) error {
	result := s.DB.Delete(&models.Item{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrItemNotFound
	}
	return nil
}
