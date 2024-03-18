package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aRestless/nexus/pkg/model"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm/clause"
)

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	authenticated := s.authenticateAdmin(r)
	if !authenticated {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var clients []model.Client

	result := s.db.Preload("ClientNetworks.Network").Preload(clause.Associations).Find(&clients)
	if result.Error != nil {
		s.handleErr(fmt.Errorf("query clients: %w", result.Error), w)
		return
	}

	response := ListClientsResponse{}
	for _, client := range clients {
		var networks []string
		for _, cn := range client.ClientNetworks {
			networks = append(networks, cn.Network.Name)
		}

		response.Items = append(response.Items, GetClientResponse{
			PublicKeyHash:   client.PublicKeyHash.String,
			HardwareAddress: client.HardwareAddress,
			Networks:        networks,
			CommonName:      client.CommonName,
		})
	}

	b, err := json.Marshal(response)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(200)
	w.Write(b)
}

func (s *Server) createOrUpdateClient(w http.ResponseWriter, r *http.Request) {
	publicKeyHash := r.Header.Get("X-Public-Key-Hash")
	macAddress := r.Header.Get("X-Hardware-Address")
	commonName := r.Header.Get("X-Common-Name")

	if publicKeyHash == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, created, err := s.findOrCreateClient(publicKeyHash, macAddress, commonName)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}

	err = s.handleResponse(w, status, &CreateClientResponse{
		PublicKeyHash:   publicKeyHash,
		CommonName:      commonName,
		HardwareAddress: macAddress,
	})

	if err != nil {
		s.handleErr(err, w)
	}
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	authenticated := s.authenticateAdmin(r)
	if !authenticated {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	publicKeyHash := chi.URLParam(r, "publicKeyHash")

	cl := s.findClientByPublicKey(publicKeyHash)

	if cl == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	for _, cn := range cl.ClientNetworks {
		err := s.revokeOtherIn(cn, 0, "")
		if err != nil {
			s.handleErr(err, w)
			return
		}

		s.db.Unscoped().Delete(cn)
	}

	s.db.Unscoped().Delete(cl)

	err := s.handleResponse(w, http.StatusOK, &DeleteClientResponse{
		PublicKeyHash:   cl.PublicKeyHash.String,
		CommonName:      cl.CommonName,
		HardwareAddress: cl.HardwareAddress,
	})

	if err != nil {
		s.handleErr(err, w)
	}
}

func (s *Server) findClientByPublicKey(publicKeyHash string) *model.Client {
	var client model.Client

	res := s.db.Preload(clause.Associations).First(&client, "public_key_hash = ?", publicKeyHash)
	if res.RowsAffected == 0 {
		return nil
	}

	return &client
}

func (s *Server) findOrCreateClient(publicKeyHash, macAddress, commonName string) (*model.Client, bool, error) {
	client := s.findClient(publicKeyHash, macAddress)

	var created bool
	if client == nil {
		client = &model.Client{
			HardwareAddress: macAddress,
			PublicKeyHash:   sql.NullString{String: publicKeyHash, Valid: true},
			CommonName:      commonName,
		}

		result := s.db.Create(client)
		if result.Error != nil {
			return nil, false, fmt.Errorf("create client: %w", result.Error)
		}
		created = true
	} else {
		client.PublicKeyHash = sql.NullString{String: publicKeyHash, Valid: true}
		client.HardwareAddress = macAddress
		client.CommonName = commonName

		result := s.db.Save(client)
		if result.Error != nil {
			return nil, false, fmt.Errorf("update client: %w", result.Error)
		}
	}

	return client, created, nil
}
func (s *Server) findClient(publicKeyHash, macAddress string) *model.Client {
	var client model.Client

	result := s.db.Preload(clause.Associations).First(&client, "public_key_hash = ? AND hardware_address = ?", publicKeyHash, macAddress)
	if result.RowsAffected > 0 {
		return &client
	}

	if macAddress == "" {
		return nil
	}

	result = s.db.Preload(clause.Associations).First(&client, "public_key_hash = ? AND hardware_address = ?", nil, macAddress)
	if result.RowsAffected == 0 {
		return nil
	}

	return &client
}
