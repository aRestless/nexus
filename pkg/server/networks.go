package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/aRestless/nexus/pkg/model"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm/clause"
)

func (s *Server) listNetworks(w http.ResponseWriter, r *http.Request) {
	authenticated := s.authenticateAdmin(r)
	if !authenticated {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var networks []model.Network
	res := s.db.Preload(clause.Associations).Find(&networks)
	if res.Error != nil {
		s.handleErr(res.Error, w)
		return
	}

	response := ListNetworksResponse{}
	for _, net := range networks {
		var groups []string
		for _, g := range net.NetworkGroups {
			groups = append(groups, g.Name)
		}

		response.Items = append(response.Items, GetNetworkResponse{
			Name:   net.Name,
			Groups: groups,
			Prefix: netip.Prefix(net.Prefix),
		})
	}

	b, err := json.Marshal(response)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(200)
	w.Write(b)
}

func (s *Server) getClientNetwork(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	network := model.Network{}
	result := s.db.Preload(clause.Associations).First(&network, "name = ?", networkName)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var resp *ClientNetworkResponse
	for _, n := range c.ClientNetworks {
		if n.NetworkID == network.ID {
			addr := n.Address.ToNetip()
			resp = &ClientNetworkResponse{
				PublicKeyHash: c.PublicKeyHash.String,
				Address:       &addr,
				Groups:        strings.Split(n.Groups, ","),
			}
			break
		}
	}

	if resp == nil {
		w.WriteHeader(404)
		return
	}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(200)
	w.Write(b)
}

func (s *Server) listClientNetworks(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	resp := ListClientNetworkResponse{}

	for _, n := range c.ClientNetworks {
		addr := netip.Addr(n.Address)
		resp.Items = append(resp.Items, ClientNetworkResponse{
			PublicKeyHash: c.PublicKeyHash.String,
			Address:       &addr,
			Groups:        strings.Split(n.Groups, ","),
		})
	}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(200)
	w.Write(b)
}

func (s *Server) createNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	req := CreateNetworkRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	network := model.Network{}
	result := s.db.Preload(clause.Associations).First(&network, "name = ?", req.Name)
	if result.RowsAffected > 0 {
		w.WriteHeader(http.StatusConflict)
		return
	}

	network.Name = req.Name
	network.Prefix = model.Prefix(req.Network)

	s.db.Create(&network)

	network.Name = req.Name
	network.Prefix = model.Prefix(req.Network)

	s.db.Create(&network)

	resp := &CreateNetworkResponse{
		Name:   network.Name,
		Prefix: netip.Prefix(network.Prefix),
		Groups: []string{},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(201)
	w.Write(b)
}

func (s *Server) listNetworkClients(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	network := model.Network{}
	s.db.Preload("ClientNetworks.Client").Preload(clause.Associations).Find(&network, "name = ?", networkName)

	resp := ListClientNetworksResponse{}
	for _, clientNetwork := range network.ClientNetworks {
		addr := clientNetwork.Address.ToNetip()
		resp.Items = append(resp.Items, GetClientNetworkResponse{
			PublicKeyHash: clientNetwork.Client.PublicKeyHash.String,
			Address:       &addr,
			Groups:        strings.Split(clientNetwork.Groups, ","),
			IsLighthouse:  clientNetwork.IsLighthouse,
			Subnets:       clientNetwork.Subnets.ToNetip(),
		})
	}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(b)
}

func (s *Server) createNetworkClient(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	req := CreateNetworkClientRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	client := s.findClientByPublicKey(req.PublicKeyHash)
	if client == nil {
		s.handleErr(fmt.Errorf("client does not exist: %s", req.PublicKeyHash), w)
		return
	}

	network := model.Network{}
	s.db.Preload(clause.Associations).Find(&network, "name = ?", networkName)

	var address netip.Addr
	if req.Address == nil {
		address, err = network.FreeIP()
		if err != nil {
			s.handleErr(err, w)
			return
		}
	} else {
		address = *req.Address
	}

	if !network.IsFree(address) {
		s.handleErr(fmt.Errorf("address already occupied: %s", address.String()), w)
		return
	}

	clientNetwork := model.ClientNetwork{}
	result := s.db.Preload(clause.Associations).First(&clientNetwork,
		"client_id = ? AND network_id = ?", client.ID, network.ID,
	)
	if result.RowsAffected > 0 {
		w.WriteHeader(http.StatusConflict)
		return
	}

	var subnets model.Prefixes
	for _, subnet := range req.Subnets {
		subnets = append(subnets, model.Prefix(subnet))
	}

	clientNetwork = model.ClientNetwork{
		Address:      model.Addr(address),
		ClientID:     client.ID,
		NetworkID:    network.ID,
		Groups:       strings.Join(req.Groups, ","),
		IsLighthouse: req.IsLighthouse,
		Subnets:      subnets,
	}

	s.db.Create(&clientNetwork)

	resp := CreateNetworkClientResponse{
		Network:      network.Name,
		Address:      address,
		Groups:       req.Groups,
		IsLighthouse: clientNetwork.IsLighthouse,
		Subnets:      clientNetwork.Subnets.ToNetip(),
	}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(b)
}

func (s *Server) updateNetworkClient(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	req := UpdateNetworkClientRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	publicKeyHash := chi.URLParam(r, "publicKeyHash")

	client := s.findClientByPublicKey(publicKeyHash)
	if client == nil {
		s.handleErr(fmt.Errorf("client does not exist: %s", publicKeyHash), w)
		return
	}

	network := model.Network{}
	s.db.Preload(clause.Associations).Find(&network, "name = ?", networkName)

	clientNetwork := model.ClientNetwork{}
	result := s.db.Preload(clause.Associations).First(&clientNetwork,
		"client_id = ? AND network_id = ?", client.ID, network.ID,
	)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var subnets model.Prefixes
	for _, subnet := range req.Subnets {
		subnets = append(subnets, model.Prefix(subnet))
	}
	log.Printf("subnets: %v\n", subnets)

	needsRevoke := clientNetwork.IsLighthouse != req.IsLighthouse || clientNetwork.Groups != groupsToString(req.Groups) || !slices.Equal(subnets, clientNetwork.Subnets)

	if req.Address != nil {
		needsRevoke = needsRevoke || req.Address.String() != clientNetwork.Address.ToNetip().String()
	}

	if needsRevoke {
		err = s.revokeOtherIn(clientNetwork, 10*time.Minute, "")
		if err != nil {
			s.handleErr(err, w)
			return
		}
	}

	clientNetwork.IsLighthouse = req.IsLighthouse
	clientNetwork.Groups = groupsToString(req.Groups)
	clientNetwork.Subnets = subnets

	if req.Address != nil {
		clientNetwork.Address = model.Addr(*req.Address)
	}

	s.db.Save(&clientNetwork)

	resp := UpdateNetworkClientResponse{
		Network:      network.Name,
		Address:      clientNetwork.Address.ToNetip(),
		Groups:       req.Groups,
		IsLighthouse: clientNetwork.IsLighthouse,
		Subnets:      clientNetwork.Subnets.ToNetip(),
	}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func (s *Server) deleteNetworkClient(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	publicKeyHash := chi.URLParam(r, "publicKeyHash")

	client := s.findClientByPublicKey(publicKeyHash)
	if client == nil {
		s.handleErr(fmt.Errorf("client does not exist: %s", publicKeyHash), w)
		return
	}

	network := model.Network{}
	s.db.Preload(clause.Associations).Find(&network, "name = ?", networkName)

	clientNetwork := model.ClientNetwork{}
	result := s.db.Preload(clause.Associations).First(&clientNetwork, "client_id = ?", client.ID)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	err := s.revokeOtherIn(clientNetwork, 10*time.Minute, "")
	if err != nil {
		s.handleErr(err, w)
		return
	}

	s.db.Unscoped().Delete(&clientNetwork)

	resp := DeleteNetworkClientResponse{
		Network:      network.Name,
		Address:      clientNetwork.Address.ToNetip(),
		Groups:       strings.Split(clientNetwork.Groups, ","),
		IsLighthouse: clientNetwork.IsLighthouse,
		Subnets:      clientNetwork.Subnets.ToNetip(),
	}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func (s *Server) getClientNetworkCA(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	network := model.Network{}
	result := s.db.Preload(clause.Associations).First(&network, "name = ?", networkName)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	pemBytes, err := s.ca.cert.MarshalToPEM()
	if err != nil {
		s.handleErr(err, w)
		return
	}

	resp := GetCAResponse{PEM: pemBytes}

	b, err := json.Marshal(resp)
	if err != nil {
		s.handleErr(err, w)
	}

	w.WriteHeader(200)
	w.Write(b)
}

func groupsToString(groups []string) string {
	clonedGroups := slices.Clone(groups)
	slices.Sort(clonedGroups)
	return strings.Join(clonedGroups, ",")
}
