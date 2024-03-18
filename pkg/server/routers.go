package server

import (
	"encoding/json"
	"fmt"
	"github.com/aRestless/nexus/pkg/model"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm/clause"
	"net/http"
	"time"
)

func (s *Server) listRouters(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")
	var network model.Network
	res := s.db.First(&network, "name = ?", networkName)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid network: %s", networkName), w)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	var routers []model.Router
	res = s.db.Find(&routers,
		"network_id = ? AND updated_at > ?",
		network.ID,
		time.Now().Add(-4*time.Hour),
	)
	if res.Error != nil {
		s.handleErr(fmt.Errorf("finding lighthouses: %w", res.Error), w)
		return
	}

	resp := ListRoutersResponse{}
	for _, r := range routers {
		resp.Items = append(resp.Items, Router{
			NebulaIP: r.NebulaIP.ToNetip(),
			Subnet:   r.Subnet.ToNetip(),
		})
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}

func (s *Server) createRouter(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	network := model.Network{}
	res := s.db.Preload(clause.Associations).Find(&network, "name = ?", networkName)
	if res.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	req := CreateRouterRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	var hasSubnet bool
	requestedSubnet := req.Subnet.String()
	for _, sn := range clientNetwork.Subnets {
		if sn.ToNetip().String() == requestedSubnet {
			hasSubnet = true
			break
		}
	}

	if !hasSubnet {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var router model.Router
	s.db.First(&router, "network_id = ? AND nebula_ip = ? AND subnet = ?", network.ID, clientNetwork.Address, model.Prefix(req.Subnet))

	router.NetworkID = network.ID
	router.Subnet = model.Prefix(req.Subnet)
	router.NebulaIP = clientNetwork.Address
	res = s.db.Save(&router)

	if res.Error != nil {
		s.handleErr(err, w)
		return
	}

	resp := CreateRouterResponse{
		NebulaIP: clientNetwork.Address.ToNetip(),
		Subnet:   router.Subnet.ToNetip(),
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}
